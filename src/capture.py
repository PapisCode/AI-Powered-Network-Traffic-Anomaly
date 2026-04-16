from scapy.all import sniff
from features import TrafficFeatures
from model import AnomalyDetector
from alerting import initialize_log, log_result, print_alert

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
    features["max_requests_from_single_ip"],
    features["most_targeted_port_count"],
]

    try:
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

        result = detector.predict(feature_vector)

        print("\n=== Traffic Analysis (5s window) ===")
        for key, value in features.items():
            print(f"{key}: {value}")
        print(f"result: {result}")
        print("====================================\n")

        log_result(features, result)
        print_alert(result)

    except Exception as e:
        print(f"Error during traffic analysis: {e}")


def start_sniffing():
    print("Starting packet capture with feature extraction and anomaly detection...")
    initialize_log()
    sniff(prn=process_packet, store=False)