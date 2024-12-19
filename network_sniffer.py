from scapy.all import sniff

def packet_callback(packet):
    try:
        # Extract source and destination IPs and the protocol
        src_ip = packet[1].src if packet.haslayer('IP') else "N/A"
        dst_ip = packet[1].dst if packet.haslayer('IP') else "N/A"
        protocol = packet[1].proto if packet.haslayer('IP') else "N/A"
        
        print(f"[+] Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}")
    
    except Exception as e:
        print(f"Error processing packet: {e}")

def main():
    print("Starting packet capture...")
    sniff(prn=packet_callback, count=0)  # Count=0 captures indefinitely

if __name__ == "__main__":
    main()
