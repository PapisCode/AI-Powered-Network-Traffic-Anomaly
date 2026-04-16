import csv
import os
from datetime import datetime


LOG_FILE = "data/traffic_log.csv"


def initialize_log():
    """
    Creates the CSV log file with headers if it does not already exist.
    """
    os.makedirs("data", exist_ok=True)

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                "timestamp",
                "packet_count",
                "tcp_count",
                "udp_count",
                "icmp_count",
                "unique_src_ips",
                "unique_dst_ips",
                "unique_dst_ports",
                "result"
            ])


def log_result(features, result):
    """
    Appends one traffic analysis result to the CSV log.
    """
    with open(LOG_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            features["packet_count"],
            features["tcp_count"],
            features["udp_count"],
            features["icmp_count"],
            features["unique_src_ips"],
            features["unique_dst_ips"],
            features["unique_dst_ports"],
            result
        ])


def print_alert(result):
    """
    Prints a visible alert when an anomaly is detected.
    """
    if result == "ANOMALY":
        print("\n!!! ALERT: Suspicious traffic detected !!!\n")