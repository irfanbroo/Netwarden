import pyshark

# Capture live packets on the specified interface

capture = pyshark.LiveCapture(interface='Wi-Fi')

# Start the capture process
capture.sniff(packet_count=10)

# Print captured packets
for packet in capture:
    print(packet)
