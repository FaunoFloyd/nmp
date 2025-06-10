Standard Operating Procedure: NMP Network Diagnostic Toolkit

| :--- | :--- | 
| Document ID: | SOP-NET-NMP-v1.0 |
| Version: | 1.0 |
| Author: | Your Name/Team | 
| Date: | June 7, 2025 |
| Status: | Final |
1.0 Purpose
This document provides the Standard Operating Procedure (SOP) for using the NMP Network Diagnostic Toolkit (net.py). The purpose of this tool is to provide a standardized, cross-platform suite of utilities for troubleshooting and diagnosing network connectivity and performance issues within our infrastructure.
2.0 Scope
This SOP applies to all Network Administrators, System Engineers, and IT Support personnel responsible for maintaining and troubleshooting servers and network services on both Windows and Linux operating systems.
3.0 Prerequisites
Before using the NMP toolkit, ensure the following prerequisites are met on the client machine where the tests will be run:
	1. Python: Python 3.6 or newer must be installed.
	2. Git: The Git client must be installed to clone the repository.
	3. Repository Files: The NMP toolkit must be cloned from the repository. 
Bash

git clone https://github.com/your-username/nmp.git
cd nmp
	4. Python Dependencies: The required Python packages must be installed using pip. 
Bash

pip install -r requirements.txt
	5. Administrative Privileges: For certain tests (e.g., pcap capture, nping, package installation), you must run the script with administrative or sudo privileges.
4.0 General Operation
4.1 Launching the Tool
Execute the script from your terminal or command prompt.
	• On Windows: 
PowerShell

python net.py
	• On Linux (with sudo for full functionality): 
Bash

sudo python net.py
Upon launch, a banner will be displayed, followed by the main menu of available tests.
4.2 Logging
All test results are automatically saved to a timestamped log file for later review. These files are typically saved to a logs directory in the script's folder or on the user's Desktop.
	• Log file format: tool_diagn_YYYYMMDD_HHMMSS.txt
5.0 Test Procedures
This section details each diagnostic test available in the NMP toolkit.

5.1 Nmap Scan
	• Purpose: To scan a target host for open ports, running services, and OS information.
	• Execution: Select option 1 from the main menu.
	• Input Format: | Prompt | Example Input | Description | | :--- | :--- | :--- | | Enter target IP for nmap | 10.0.0.5 | The IP address of the target machine. | | Enter port for nmap | 443 or 22,80,443 | A single port or a comma-separated list of ports. |
	• Interpreting Results: | Output Scenario | What it Means (OK/Not OK) | Possible Cause / Next Step | | :--- | :--- | :--- | | Host is up... STATE open | ✅ OK | The target is reachable and the specified port is open and listening. | | STATE closed | ❌ Not OK | The target is reachable, but no application is listening on that port. Verify the service is running on the target. | | STATE filtered | ❌ Not OK | A firewall, NSG, or other network device is blocking access to the port. Check firewall rules. | | Host seems down | ❌ Not OK | The target host is not responding to pings or ARP requests. Verify the IP is correct and the host is powered on. |

5.2 Nping Test
	• Purpose: To send TCP packets to a specific port to test connectivity and latency, bypassing standard ICMP pings.
	• Execution: Select option 2 from the main menu.
	• Input Format: | Prompt | Example Input | Description | | :--- | :--- | :--- | | Enter target IP for nping | 10.0.0.5 | The IP address of the target machine. | | Enter port for nping | 3389 | The single destination port for the TCP packets. |
	• Interpreting Results: | Output Scenario | What it Means (OK/Not OK) | Possible Cause / Next Step | | :--- | :--- | :--- | | Rcvd: 20... Lost: 0 (0.00%) | ✅ OK | All packets were successfully sent and acknowledged, indicating excellent connectivity. | | Lost: > 0 | ❌ Not OK | Some packets were lost in transit. This indicates network instability, congestion, or firewall issues. | | Failed to resolve target | ❌ Not OK | The hostname could not be resolved to an IP address. Check for DNS issues. |

5.3 Curl Tests
	• Purpose: To perform advanced diagnostics on HTTP/S services.
	• Execution: Select option 3 from the main menu, then select a sub-test.
5.3.1 HTTP Header Check
	• OK ✅: HTTP/2 200 OK. The web service is responding correctly.
	• Not OK ❌: 4xx or 5xx status codes (404 Not Found, 503 Service Unavailable), Could not resolve host, or Connection refused.
5.3.2 TCP Port Connectivity
	• OK ✅: The output contains the line * Connected to <target> (<ip>) port <port>.
	• Not OK ❌: * connect to ... failed: Connection timed out or Connection refused. Indicates a firewall block or no service listening.
5.3.3 Detailed Latency/Timing Test
	• This test provides performance metrics. High values are Not OK. 
		○ High DNS Lookup Time: Indicates a slow or unresponsive DNS server.
		○ High Time to First Byte: Indicates a slow backend application or database on the server, rather than a network issue.

5.4 Extended Ping Test
	• Purpose: A standard, continuous ICMP ping to check basic reachability and packet loss over time.
	• Execution: Select option 4 from the main menu.
	• Input Format: | Prompt | Example Input | Description | | :--- | :--- | :--- | | Enter target IP... | 8.8.8.8 | The IP address or domain to ping. |
	• Interpreting Results: | Output Scenario | What it Means (OK/Not OK) | Possible Cause / Next Step | | :--- | :--- | :--- | | Reply from <IP>... 0% loss | ✅ OK | The target is fully reachable with no packet loss. | | Request timed out | ❌ Not OK | Packets are not reaching the destination or the replies are not getting back. Check for routing or firewall issues. | | Destination host unreachable | ❌ Not OK | A routing problem exists between the source and destination. Check local routing tables. |

5.5 PCAP Capture
	• Purpose: To capture all network traffic to/from a target IP for deep analysis with tools like Wireshark.
	• Execution: Select option 5. Requires admin/sudo privileges.
	• Input Format: | Prompt | Example Input | Description | | :--- | :--- | :--- | | Enter target IP... | 10.0.0.5 | The IP whose traffic you want to capture. |
	• Interpreting Results: | Output Scenario | What it Means (OK/Not OK) | Next Step | | :--- | :--- | :--- | | PCAP capture completed. File saved to... | ✅ OK | The capture was successful. | | permission denied or operation requires elevation | ❌ Not OK | The script was not run with sufficient privileges. |

5.6 MTU Discovery Test
	• Purpose: To find the largest network packet size that can travel to a host without fragmentation.
	• Execution: Select option 6.
	• Input Format: | Prompt | Example Input | Description | | :--- | :--- | :--- | | Enter target IP or domain... | www.google.com | The destination for the test. |
	• Interpreting Results: | Output Scenario | What it Means (OK/Not OK) | Next Step | | :--- | :--- | :--- | | SUCCESS! Optimal MTU... is XXXX | ✅ OK | The test successfully identified the optimal MTU for the path. | | MTU Discovery Failed. | ❌ Not OK | The tool could not get a successful ping in the tested range, indicating a more complex connectivity issue. |

5.7 List Active Connections (netstat)
	• Purpose: To display all active network connections and listening ports on the local machine.
	• Execution: Select option 7.
	• Input Format: None.
	• Interpreting Results: This is an informational tool. 
		○ Look for LISTENING in the State column to see which ports are open for incoming connections.
		○ Look for ESTABLISHED to see active, ongoing connections.
		○ Use this to verify your application is listening on the correct port or to identify unexpected network activity.

6.0 Full Diagnostic Procedure
Selecting option 8 runs a consolidated series of tests (Nmap, Nping, Curl, Ping, PCAP) against a single target. The user will be prompted for the target IP and port once, and the script will execute the tests sequentially. Interpret the results for each section as detailed above.
![image](https://github.com/user-attachments/assets/a0f87676-8493-4c24-8e86-0efd121cc57e)
