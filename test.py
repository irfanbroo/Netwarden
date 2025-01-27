import pyshark
import nmap

# Arp spoofing 
def detect_arp_spoofing(packet, arp_cache):
    issues = []
    try:

    
        if packet.eth.type  == "0x0806":  # Check if it's an ARP packet
            arp_src_ip = packet.arp.src_proto_ipv4
            arp_src_mac = packet.arp.src_hw_mac
            
            if arp_src_ip in arp_cache and arp_cache[arp_src_ip] != arp_src_mac:
                issue = f"ARP spoofing detected: IP {arp_src_ip} seen with MAC {arp_src_mac}, expected {arp_cache[arp_src_ip]}"
                if issue not in issue:
                    issues.append(issue)
            else:
                arp_cache[arp_src_ip] = arp_src_mac
    except AttributeError as e:
        print(f"Skipping ARP packet due to missing attribute: {e}")
    
    return issues
    




def detect_spoofing(packet,mac_ip_map):
    
    issues = []

    try:
        
        source_ip = packet.ip.src if hasattr(packet, 'ip') else None
        source_mac = packet.eth.src if hasattr(packet, 'eth') else None

        if source_ip and source_mac:
            
            # Check for IP/MAC mismatch
            if source_ip in mac_ip_map and mac_ip_map[source_ip] != source_mac:
                issue = f"IP/MAC mismatch: IP {source_ip} seen with MAC {source_mac}, expected {mac_ip_map[source_ip]}"
                
                if issue not in issues:
                    issues.append(issue)
            
            else:
                mac_ip_map[source_ip] = source_mac
    except AttributeError as e:
        print(f"Skipping packet due to missing attribute: {e}")
    
    return issues



def analyse_packets(data,map_ip_nmap,arp_cache):
    
    suspicious_packets = []
    
    for packet in data:
        try:
            # Extract key details for analysis
            
            source_ip = packet.ip.src if hasattr(packet, 'ip') else None
            
            dest_ip = packet.ip.dst if hasattr(packet, 'ip') else None
            
            protocol = packet.highest_layer
            
            length = int(packet.length) if hasattr(packet, 'length') else 0
            
            dns_query = packet.dns.qry_name if hasattr(packet, 'dns') else None
            
            tcp_flags = packet.tcp.flags if hasattr(packet, 'tcp') else None

            source_port = int(packet.tcp.srcport) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') else None

            dest_port = int(packet.tcp.dstport) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport') else None

            # Now we define our suspiscious patterns 

            suspicious_dns_patterns = ["malicious", "phishing", "dangerous"]
            if protocol == "DNS" and dns_query and any(pattern in dns_query for pattern in suspicious_dns_patterns):
                suspicious_packets.append(
                    {
                        "type": "suspiscious DNS query", "details": dns_query}
                        
                )
            elif protocol == "TCP" and tcp_flags == "0x0002":
                suspicious_packets.append(
                    {
                        "type": "Potential SYN scan", "details": f"from {source_ip}"}

                )

            elif length > 1000:
                suspicious_packets.append(
                    {"type": "Large packet size", "details": f"Size: {length}"}
                )
            
            elif source_ip and dest_ip and source_ip.startswith("192.168") and dest_ip.startswith("10."):
                suspicious_packets.append(
                    {"type": "Unusual internal traffic", "details": f"{source_ip} -> {dest_ip}"}
                )
        
            elif protocol == "TCP" and tcp_flags == "0x0018":  # PSH + ACK flags
                if source_port in [4444, 31337] or dest_port in [4444, 31337]:
                    suspicious_packets.append(
                        {
                        "type": "Potential Netcat usage",
                        "details": f"Source {source_ip}:{source_port} -> Destination {dest_ip}:{dest_port}",
                        }
                    )          
            
            # Spoofing Detection
            spoof_issues = detect_spoofing(packet,map_ip_nmap)
            for issue in spoof_issues:
                suspicious_packets.append({"type": "spoofing detected", "details": issue})


            # ARP Spoofing Detection

            arp_issues = detect_arp_spoofing(packet, arp_cache)
            for issue in arp_issues:
                suspicious_packets.append({"type": "ARP spoofing detected", "details": issue})


        except AttributeError as e:
            # Handling the Attribute error by skipping through
            print(f"Skipping packet due to missing attribute: {e}")
            continue
    
    return suspicious_packets     


# Nmap scan 
def perform_nmap_scan(ip):
    
    # Initialize nmap scanner
    
    scanner = nmap.PortScanner()
    print(f"Performing Nmap scan on {ip}...")
    try:
        scan_result = scanner.scan(ip, arguments= '-Pn -sS -T4')
        return scan_result['scan'][ip] if ip in scan_result['scan'] else None
    
    except Exception as e:
        print(f"Error during Nmap scan: {e}")
        return None





# Capture live packets on the specified interface

capture = pyshark.LiveCapture(interface='Wi-Fi')


# Start the capture process
capture.sniff(packet_count=5)

data=[]
# Print captured packets
for packet in capture:
    data.append(packet)

mac_ip_map = {}
arp_cache = {}
suspicious_activity = analyse_packets(data,mac_ip_map,arp_cache)

if suspicious_activity:
    print("Suspicious activity detected")
    for activity in suspicious_activity:
        print(f"{activity['type']}: {activity['details']}")

    
    # Perform Nmap scan for each suspicious source IP

    unique_ips = set()
    
    for activity in suspicious_activity:
        if "from" in activity['details']:
            unique_ips.add(activity['details'].split("from")[-1].strip())

    nmap_results = {}
    for ip in unique_ips:
        nmap_result = perform_nmap_scan(ip)
        nmap_results[ip] = nmap_result


    
    
    
    
    # Saving suspicious activity and nmap results to a file to file
    with open("suspicious_activity.log", "w") as log_file:
        for activity in suspicious_activity:
            log_file.write(f"{activity['type']}: {activity['details']}\n")

        for ip, result in nmap_results.items():
            log_file.write(f"{ip}: {result}\n")


else:
    print("No suspicious activity detected.")




    
    
       
