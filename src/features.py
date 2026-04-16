import time
from collections import defaultdict


class TrafficFeatures:
    def __init__(self, window_size=5):
        self.window_size = window_size
        self.reset_window()

    def reset_window(self):
        self.start_time = time.time()
        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0

        self.src_ips = set()
        self.dst_ips = set()
        self.dst_ports = set()

    def process_packet(self, packet):
        from scapy.all import IP, TCP, UDP, ICMP

        if not packet.haslayer(IP):
            return None

        self.packet_count += 1

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        self.src_ips.add(src_ip)
        self.dst_ips.add(dst_ip)

        if packet.haslayer(TCP):
            self.tcp_count += 1
            self.dst_ports.add(packet[TCP].dport)

        elif packet.haslayer(UDP):
            self.udp_count += 1
            self.dst_ports.add(packet[UDP].dport)

        elif packet.haslayer(ICMP):
            self.icmp_count += 1

        # Check if window expired
        if time.time() - self.start_time >= self.window_size:
            features = self.get_features()
            self.reset_window()
            return features

        return None

    def get_features(self):
        return {
            "packet_count": self.packet_count,
            "tcp_count": self.tcp_count,
            "udp_count": self.udp_count,
            "icmp_count": self.icmp_count,
            "unique_src_ips": len(self.src_ips),
            "unique_dst_ips": len(self.dst_ips),
            "unique_dst_ports": len(self.dst_ports),
        }