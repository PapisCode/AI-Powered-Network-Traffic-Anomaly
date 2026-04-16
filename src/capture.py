from scapy.all import sniff, IP, TCP, UDP, ICMP


def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            print(f"[TCP] {src_ip}:{packet[TCP].sport} -> {dst_ip}:{packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print(f"[UDP] {src_ip}:{packet[UDP].sport} -> {dst_ip}:{packet[UDP].dport}")

        elif packet.haslayer(ICMP):
            print(f"[ICMP] {src_ip} -> {dst_ip}")

        else:
            print(f"[OTHER] {src_ip} -> {dst_ip}")


def start_sniffing(packet_count=20):
    print("Starting packet capture...")
    sniff(prn=process_packet, count=packet_count, store=False)
    print("Packet capture finished.")
