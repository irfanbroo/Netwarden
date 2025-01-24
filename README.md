
---

# Netwarden

Netwarden is a network monitoring tool designed to detect suspicious network activities, capture real-time network packets, and perform security audits using Nmap. It is useful for network administrators, penetration testers, and security enthusiasts. The tool aims to identify abnormal traffic patterns and security threats, while also providing detailed reports for further analysis.

## Features

- **Real-time Packet Capture**: Continuously captures network packets from a specified network interface, such as Wi-Fi or Ethernet.
- **Suspicious Activity Detection**: Analyzes network traffic for suspicious patterns such as large packet sizes, unusual internal traffic, and malicious DNS queries.
- **Nmap Scanning**: Automatically performs Nmap scans on suspicious IP addresses to gather more information on potential threats.
- **Customizable Detection Patterns**: Easily modify or add new detection patterns to identify specific types of suspicious network activity.
- **Detailed Logs**: Saves detected suspicious activities and Nmap scan results to a log file for further analysis.
- **Cross-Platform**: Works across major operating systems like Windows, Linux, and macOS.

## Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [How It Works](#how-it-works)
6. [Customization](#customization)
7. [Example Output](#example-output)
8. [Logging](#logging)
9. [Contributing](#contributing)
10. [License](#license)
11. [Contact](#contact)

## Introduction

Netwarden is designed to provide a simple yet powerful way to monitor and analyze network traffic for signs of suspicious or malicious activity. By using `pyshark` for packet capture and `nmap` for vulnerability scanning, Netwarden helps system administrators and security experts detect potential threats in real-time.

This tool can be used to analyze network traffic, perform vulnerability assessments, and identify potential attack vectors such as SYN scans or DNS poisoning.

## Installation

### Prerequisites

To use Netwarden, you need the following tools and libraries:

- **Python 3.x**: The latest version of Python.
- **pyshark**: A Python wrapper for the Wireshark network protocol analyzer to capture packets.
- **nmap**: A powerful network scanning tool for identifying active devices, open ports, and potential vulnerabilities.
- **Root or Administrator Privileges**: Required for packet capturing on most systems.

### Install Dependencies

1. **Clone the Repository**:
   To begin, clone the repository to your local machine:
   ```bash
   git clone https://github.com/irfanbroo/Netwarden.git
   cd Netwarden
   ```

2. **Create a Virtual Environment** (optional but recommended):
   It's a good practice to use a virtual environment to manage dependencies.
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. **Install Python Dependencies**:
   Install the required Python packages using `pip`:
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Nmap**:

   - **Linux**:
     Use the following command to install Nmap:
     ```bash
     sudo apt-get install nmap
     ```

   - **Windows**:
     Download and install Nmap from the [official website](https://nmap.org/download.html).

   - **macOS**:
     Use Homebrew to install Nmap:
     ```bash
     brew install nmap
     ```

5. **Verify the Installation**:
   To verify that everything is installed properly, run the following command:
   ```bash
   python netwarden.py
   ```

   If everything is set up correctly, the script will start monitoring network traffic.

## Usage

### Running Netwarden

1. **Start the Script**:
   Simply run the `netwarden.py` script to begin capturing network packets and analyzing suspicious activities:
   ```bash
   python netwarden.py
   ```

2. **Network Interface**:
   The script captures packets from the default network interface (`Wi-Fi` by default). You can change this in the script to use Ethernet or any other interface on your machine.

3. **Suspicious Activity Detection**:
   Once the script begins capturing packets, it will analyze the traffic for suspicious activity. If any suspicious activity is detected (e.g., SYN scans, unusual DNS queries, large packets), it will print the details to the console and log them in a file.

4. **Perform Nmap Scans**:
   For any suspicious IP addresses detected during packet analysis, the script will automatically perform an Nmap scan. The scan results will also be logged for later inspection.

### Example Output

```text
Suspicious activity detected:
Suspicious DNS query: malicious.example.com
Potential SYN scan: from 192.168.1.100
Large packet size: Size: 1200
Unusual internal traffic: 192.168.1.100 -> 10.0.0.1

Performing Nmap scan on 192.168.1.100...
Nmap scan result: {'host': {'status': {'state': 'up'}, 'addresses': {'ipv4': '192.168.1.100'}}}
```

The above output shows that a suspicious DNS query was detected, followed by a SYN scan from the IP `192.168.1.100`. The tool performs an Nmap scan to gather more information about this IP.

### Log File

All suspicious activities and Nmap scan results are saved in the `suspicious_activity.log` file for later review:
```
Suspicious DNS query: malicious.example.com
Potential SYN scan: from 192.168.1.100
Large packet size: Size: 1200
Unusual internal traffic: 192.168.1.100 -> 10.0.0.1

Nmap Scan Results:
192.168.1.100: {'host': {'status': {'state': 'up'}, 'addresses': {'ipv4': '192.168.1.100'}}}
```

## How It Works

Netwarden works by capturing packets from a specified network interface using the `pyshark` library. It then analyzes the captured packets for suspicious patterns based on predefined rules.

1. **Packet Capture**: The tool listens for network traffic on the selected interface (e.g., Wi-Fi or Ethernet).
2. **Suspicious Activity Detection**: The script checks for specific patterns like:
   - **DNS Queries**: Identifies malicious or phishing queries.
   - **SYN Scans**: Detects potential SYN floods or port scanning activities.
   - **Large Packet Sizes**: Flags unusually large packets which could indicate data exfiltration attempts.
   - **Unusual Internal Traffic**: Flags traffic between certain internal subnets that may indicate lateral movement.
3. **Nmap Scan**: For each suspicious IP address detected, an Nmap scan is performed to gather more information about open ports, services, and potential vulnerabilities.
4. **Logging**: Detected suspicious activities and the results of Nmap scans are logged for later analysis.

## Customization

### Add Suspicious DNS Patterns

You can customize the detection of suspicious DNS queries by adding new patterns to the `suspicious_dns_patterns` list in the `analyse_packets` function:
```python
suspicious_dns_patterns = ["malicious", "phishing", "dangerous", "example.com"]
```

### Modify TCP Flag Detection

The script currently detects potential SYN scans based on the `tcp.flags` attribute. You can modify this logic to detect other types of attacks by adjusting the `tcp_flags` check.

### Changing the Network Interface

By default, Netwarden listens on the `Wi-Fi` network interface. To capture packets from a different interface, change the `interface` parameter in the `LiveCapture` function:
```python
capture = pyshark.LiveCapture(interface='eth0')  # For Ethernet interface
```

## Example Configuration

Here’s an example of how to configure custom patterns and modify the interface to capture packets from a different network:

```python
def analyse_packets(data):
    suspicious_dns_patterns = ["malicious", "example.com", "phishing"]
    capture = pyshark.LiveCapture(interface='eth0')
    # Continue with the rest of the logic...
```

## Logging

Netwarden logs all suspicious activities and Nmap scan results to a file (`suspicious_activity.log`). This allows for a thorough review of detected issues and helps track potential security concerns over time.

The log file contains entries for each suspicious activity detected, followed by any relevant Nmap results:
```
Suspicious DNS query: phishing.example.com
Potential SYN scan: from 192.168.1.50
Large packet size: Size: 1500
Unusual internal traffic: 192.168.1.50 -> 10.0.0.5
```

## Contributing

We welcome contributions to Netwarden! If you'd like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes and commit them (`git commit -am 'Add new feature'`).
4. Push to your fork (`git push origin feature-branch`).
5. Open a Pull Request to merge your changes into the main repository.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For any questions, issues, or feedback, feel free to open an issue or contact the project maintainers directly.

---
