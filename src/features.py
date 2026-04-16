import time


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

        # New tracking dictionaries for Phase 5
        self.src_ip_counts = {}
        self.port_access_counts = {}

    def process_packet(self, packet):
        from scapy.all import IP, TCP, UDP, ICMP

        if not packet.haslayer(IP):
            return None

        self.packet_count += 1

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = None

        self.src_ips.add(src_ip)
        self.dst_ips.add(dst_ip)

        # Track how many packets come from each source IP
        self.src_ip_counts[src_ip] = self.src_ip_counts.get(src_ip, 0) + 1

        if packet.haslayer(TCP):
            self.tcp_count += 1
            dst_port = packet[TCP].dport
            self.dst_ports.add(dst_port)

        elif packet.haslayer(UDP):
            self.udp_count += 1
            dst_port = packet[UDP].dport
            self.dst_ports.add(dst_port)

        elif packet.haslayer(ICMP):
            self.icmp_count += 1

        # Track how often each destination port is targeted
        if dst_port is not None:
            self.port_access_counts[dst_port] = self.port_access_counts.get(dst_port, 0) + 1

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
            "max_requests_from_single_ip": max(self.src_ip_counts.values(), default=0),
            "most_targeted_port_count": max(self.port_access_counts.values(), default=0),
        }