from scapy.all import sniff
from features import TrafficFeatures
from model import AnomalyDetector

feature_extractor = TrafficFeatures(window_size=5)
detector = AnomalyDetector()
training_data = []
TRAINING_TARGET = 10


def process_packet(packet):
    features = feature_extractor.process_packet(packet)

    if not features:
        return

    feature_vector = [
        features["packet_count"],
        features["tcp_count"],
        features["udp_count"],
        features["icmp_count"],
        features["unique_src_ips"],
        features["unique_dst_ips"],
        features["unique_dst_ports"],
    ]

    try:
        # Collect training data first
        if not detector.trained:
            training_data.append(feature_vector)

            print(f"\nCollecting training data... ({len(training_data)}/{TRAINING_TARGET})")
            for key, value in features.items():
                print(f"{key}: {value}")

            if len(training_data) == TRAINING_TARGET:
                print("\nTraining anomaly detection model...")
                detector.train(training_data)
                print("Model trained successfully.")

            print()
            return

        # Predict after training
        result = detector.predict(feature_vector)

        print("\n=== Traffic Analysis (5s window) ===")
        for key, value in features.items():
            print(f"{key}: {value}")
        print(f"result: {result}")
        print("====================================\n")

    except Exception as e:
        print(f"Error during traffic analysis: {e}")


def start_sniffing():
    print("Starting packet capture with feature extraction and anomaly detection...")
    sniff(prn=process_packet, store=False)