import pyshark

def analyse_packets(data):
    
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
        
        except AttributeError as e:
            # Handling the Attribute error by skipping through
            print(f"Skipping packet due to missing attribute: {e}")
            continue
    
    return suspicious_packets     


# Capture live packets on the specified interface

capture = pyshark.LiveCapture(interface='Wi-Fi')


# Start the capture process
capture.sniff(packet_count=5)

data=[]
# Print captured packets
for packet in capture:
    data.append(packet)


suspicious_activity = analyse_packets(data)

if suspicious_activity:
    print("Suspicious activity detected")
    for activity in suspicious_activity:
        print(f"{activity['type']}: {activity['details']}")

    # Saving suspicious activity to file
    with open("suspicious_activity.log", "w") as log_file:
        for activity in suspicious_activity:
            log_file.write(f"{activity['type']}: {activity['details']}\n")

else:
    print("No suspicious activity detected.")




    
    
       