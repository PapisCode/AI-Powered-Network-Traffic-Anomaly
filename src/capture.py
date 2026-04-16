from scapy.all import sniff
from features import TrafficFeatures

feature_extractor = TrafficFeatures(window_size=5)


def process_packet(packet):
    features = feature_extractor.process_packet(packet)

    if features:
        print("\n=== Traffic Summary (5s window) ===")
        for key, value in features.items():
            print(f"{key}: {value}")
        print("==================================\n")


def start_sniffing():
    print("Starting packet capture with feature extraction...")
    sniff(prn=process_packet, store=False)
