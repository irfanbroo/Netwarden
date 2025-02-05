
# Network Traffic Monitoring and Threat Detection Tool

My First ambitious python script, hope yall have some use with this. 
"Keeping Your Network Safe, One Packet at a Time" 

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [System Architecture](#system-architecture)
    - [Packet Capture](#packet-capture)
    - [Threat Analysis](#threat-analysis)
    - [Nmap Integration](#nmap-integration)
    - [Logging and Reporting](#logging-and-reporting)
4. [Installation](#installation)
    - [Prerequisites](#prerequisites)
    - [Setup Instructions](#setup-instructions)
5. [How to Use](#how-to-use)
    - [Configuration](#configuration)
    - [Running the Tool](#running-the-tool)
6. [Detailed Functionality](#detailed-functionality)
    - [DNS Tunneling Detection](#dns-tunneling-detection)
    - [ARP Spoofing Detection](#arp-spoofing-detection)
    - [IP/MAC Spoofing Detection](#ipmac-spoofing-detection)
    - [SYN Scan Detection](#syn-scan-detection)
    - [Unusual Traffic Pattern Detection](#unusual-traffic-pattern-detection)
7. [Example Outputs](#example-outputs)
    - [Terminal Output](#terminal-output)
    - [Log File Example](#log-file-example)
    - [Nmap Scan Results](#nmap-scan-results)
8. [Real-Life Applications](#real-life-applications)
9. [Known Limitations](#known-limitations)
10. [Future Work](#future-work)
11. [FAQs](#faqs)
12. [Contributing](#contributing)
13. [License](#license)

---

## 1. Overview

The **Network Traffic Monitoring and Threat Detection Tool** is a Python-based application that provides real-time analysis of network traffic to identify potential security threats. It combines packet capture (`pyshark`) with network vulnerability scanning (`nmap`) to offer a robust and actionable security monitoring solution.

This tool is designed for:
- **System Administrators**: To monitor network health and identify malicious activities.
- **Cybersecurity Analysts**: To detect threats like ARP spoofing, DNS tunneling, and SYN scans.
- **Educators**: As a practical demonstration of network security concepts.

---

## 2. Features

### Core Capabilities
- **Real-Time Monitoring**: Captures live network packets from the specified interface.
- **Threat Detection**:
  - DNS tunneling (long queries or high request frequency).
  - ARP spoofing (conflicting IP/MAC mappings).
  - SYN scans (common reconnaissance technique).
  - Spoofed IP/MAC addresses.
  - Unusual internal traffic patterns.
- **Integrated Nmap Scanning**: Automatically scans flagged IPs to identify open ports and vulnerabilities.
- **Comprehensive Logs**: Saves all detected activities and Nmap results for auditing.

### Customization
- Modify detection thresholds (e.g., query lengths, ARP mappings).
- Update the interface or packet count for specific use cases.

---

## 3. System Architecture

This tool operates in four main stages:

### 3.1 Packet Capture
- Uses the `pyshark` library to capture packets from a specified interface.
- Captures TCP, UDP, ARP, and DNS packets for analysis.

### 3.2 Threat Analysis
- Applies heuristic rules to identify anomalies, such as:
  - Long DNS queries (>225 characters).
  - IP/MAC mismatches.
  - SYN flags without corresponding ACKs.

### 3.3 Nmap Integration
- Suspicious source IPs are scanned using Nmap to uncover:
  - Open ports.
  - Services running on the host.
  - Potential vulnerabilities.

### 3.4 Logging and Reporting
- Detailed logs are saved in `suspicious_activity.log`.
- Logs include timestamps, detected threats, and Nmap results.

---

## 4. Installation

### 4.1 Prerequisites
- **Python 3.x**: Ensure Python is installed on your system.
- **Wireshark/tshark**: Install Wireshark, and ensure `tshark` is in your PATH.
- **Nmap**: Install Nmap for scanning flagged IPs.
- Required Python libraries:
  ```bash
  pip install pyshark python-nmap
  ```

### 4.2 Setup Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/irfanbroo/Netwarden.git
   cd Netwarden
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 5. How to Use

### 5.1 Configuration
Modify the script to specify your desired network interface:
```python
capture = pyshark.LiveCapture(interface='Wi-Fi')
```

Set detection thresholds in the corresponding functions:
- **DNS Tunneling**:
  ```python
  if len(query) > 225:
  ```
- **High DNS Query Frequency**:
  ```python
  if dns_tracker[src_ip] > 50:
  ```

### 5.2 Running the Tool
Run the script using:
```bash
python network_analysis.py
```

---

## 6. Detailed Functionality

### DNS Tunneling Detection
- Monitors DNS queries for unusual characteristics:
  - Query lengths >225 characters.
  - High-frequency requests (>50 queries per source IP).

### ARP Spoofing Detection
- Tracks IP/MAC mappings.
- Flags packets where the observed MAC address doesn’t match the expected one for a given IP.

### IP/MAC Spoofing Detection
- Compares source IPs and MAC addresses against a known mapping.
- Flags mismatches as potential spoofing.

### SYN Scan Detection
- Identifies TCP packets with only the SYN flag set.
- Commonly used in reconnaissance scans.

### Unusual Traffic Pattern Detection
- Detects traffic with unexpected internal IP ranges or patterns.

---

## 7. Example Outputs

### 7.1 Terminal Output
```plaintext
Suspicious activity detected:
- DNS Tunneling: Potential DNS tunneling detected: maliciousquery.example.com
- ARP Spoofing: IP 192.168.1.2 seen with MAC aa:bb:cc:dd:ee:ff, expected ff:ee:dd:cc:bb:aa
- SYN Scan: From 192.168.1.5
Performing Nmap scan on 192.168.1.5...
```

### 7.2 Log File Example
```plaintext
DNS Tunneling: Potential DNS tunneling detected: maliciousquery.example.com
ARP Spoofing: IP 192.168.1.2 seen with MAC aa:bb:cc:dd:ee:ff, expected ff:ee:dd:cc:bb:aa
SYN Scan: From 192.168.1.5

Nmap Scan Results:
192.168.1.5:
  Ports:
    22 (SSH): Open
    80 (HTTP): Open
```

### 7.3 Nmap Scan Results
```plaintext
Host: 192.168.1.5
Open Ports:
  - 22 (SSH)
  - 80 (HTTP)
  - 443 (HTTPS)
```

---

## 8. Real-Life Applications

1. **Enterprise Security Monitoring**:
   Detect and respond to potential threats in real-time.
2. **Incident Response**:
   Investigate anomalies and generate actionable insights.
3. **Educational Tools**:
   Demonstrate network security techniques.

---

## 9. Known Limitations
- **Encrypted Traffic**: Cannot analyze HTTPS or other encrypted protocols.
- **False Positives**: May occasionally flag benign traffic as suspicious.
- **Performance**: Heavy traffic volumes may impact performance.

---

## 10. Future Work
- Add support for HTTPS decryption.
- Introduce anomaly detection using machine learning.
- Build a web-based dashboard for real-time visualization.

---

## 11. FAQs

### Q: What permissions are required?
A: The script may require administrative privileges to capture packets.

### Q: Can I use this on a Wi-Fi network?
A: Yes, specify your Wi-Fi interface in the configuration.

---

## 12. Contributing
Contributions are welcome! Please submit a pull request or open an issue to discuss potential changes.

---

## 13. License
This project is licensed under the MIT License. See the LICENSE file for more details.

--- 

